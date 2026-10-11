from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import os
import time
from unittest.mock import patch

import pytest

from test_setup_recovery_sssd_policy import scenario as policy_fixture


def scenario(root):
    from alt_deploy import setup_recovery_services as services, setup_recovery_start_graph as graph
    import test_setup_recovery_kerberos as kerberos_fixture
    original_apply = kerberos_fixture.apply
    states = {}; calls = []; saved = {}
    for unit in services.UNITS:
        state = {key: '' for key in graph.PROPERTIES}
        state.update(Id=unit, Names=unit, LoadState='loaded', ActiveState='inactive', SubState='dead',
            MainPID='0', ControlPID='0', KillMode='control-group',
            FragmentPath='/usr/lib/systemd/system/' + unit, NeedDaemonReload='no',
            SuccessAction='none', FailureAction='none', StartLimitAction='none', StopWhenUnneeded='no',
            Restart='on-abnormal' if unit == 'sssd.service' else 'no', RestartMode='normal',
            NRestarts='0', Type='notify', RefuseManualStart='no', RefuseManualStop='no')
        if unit in ('smb.service', 'nmb.service'): state.update(ActiveState='active', SubState='running', MainPID='100')
        states[unit] = state
    def service_runner(command, **options):
        calls.append(command)
        if command[0] == '/usr/bin/rpm':
            package = 'sssd 2.9.8-alt3' if command[2].endswith('/sssd.service') else 'systemd 258.9-alt1'
            return 0, package + '\n', ''
        if command[1] == 'is-active':
            return 3, '\n'.join(states[unit]['ActiveState'] for unit in services.UNITS) + '\n', ''
        if command[1] == 'list-jobs': return 0, '', ''
        if command[-1] == '--property=UnitPath': return 0, 'UnitPath=' + ' '.join(graph.UNIT_PATHS) + '\n', ''
        if command[1] == 'show':
            unit = command[-1] if command[-2] == '--' else command[2]
            properties = next(item for item in command if item.startswith('--property=')).removeprefix('--property=').split(',')
            return 0, ''.join(key + '=' + states[unit][key] + '\n' for key in properties), ''
        if command[1] == 'stop':
            states[command[2]].update(ActiveState='inactive', SubState='dead', MainPID='0')
            return 0, '', ''
        assert command == ['/usr/bin/systemctl', 'start', 'sssd.service', '--job-mode=ignore-requirements']
        from alt_deploy import setup_recovery_sssd_start as start
        leaf = start.path_for(saved['request'], backup=saved['args']['backup'], root=root)
        assert (leaf / 'start-intent.json').is_file()
        states['sssd.service'].update(ActiveState='active', SubState='running', MainPID='123', InvocationID='a' * 32)
        return 0, '', ''
    def quiesce_then_import(data):
        for unit in services.UNITS:
            path = root / states[unit]['FragmentPath'].lstrip('/'); path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'SYNTHETIC_STOCK_UNIT'); path.chmod(0o644)
        tool = root / 'usr/bin/systemctl'; tool.write_bytes(b'SYNTHETIC_SYSTEMCTL'); tool.chmod(0o755)
        args = {key:data[key] for key in ('backup', 'probe', 'collect', 'root', 'owner')}
        snapshot = services.snapshot(**args, runner=service_runner)
        bound = data['request']['rehearsal_request']
        request = dict(schema_version=1, backup_request=bound['backup_request'], backup_receipt=bound['backup_receipt'],
            services=snapshot, services_sha256=data['backup'].digest(snapshot), source_sha256='d' * 64)
        receipt = services.quiesce_once(request, **args, importer=__import__('alt_deploy.setup_recovery_import', fromlist=['x']), runner=service_runner)
        saved.update(service_request=request, service_receipt=receipt)
        return original_apply(data)
    with patch.object(kerberos_fixture, 'apply', quiesce_then_import):
        policy, prepared, args, _ = policy_fixture(root)
    policy_receipt = policy.install_once(prepared, **args)
    original_runner = args['runner']
    def runner(command, **options):
        if command[0] == '/usr/bin/systemctl' or (command[0] == '/usr/bin/rpm' and
                (command[2] == '/usr/bin/systemctl' or command[2].startswith('/usr/lib/systemd/system/'))):
            return service_runner(command, **options)
        return original_runner(command, **options)
    args.update(policy=policy, services=services, graph=graph, runner=runner)
    unit = graph._unit('sssd.service', runner=runner, probe=args['probe'], root=root, owner=os.geteuid(), deadline=time.monotonic() + 30)
    request = dict(schema_version=1, policy_request=prepared, policy_receipt=policy_receipt,
        service_request=saved['service_request'], service_receipt=saved['service_receipt'], sssd_unit=unit,
        source_sha256='e' * 64, effects_ledger_sha256='f' * 64, plan_id='recovery-' + '2' * 64,
        plan_sha256='2' * 64, approval_sha256='3' * 64,
        plan_created_at=datetime.now(timezone.utc).isoformat(),
        plan_expires_at=(datetime.now(timezone.utc)+timedelta(minutes=30)).isoformat())
    request['plan_expires_at']=(datetime.fromisoformat(request['plan_created_at'])+timedelta(minutes=30)).isoformat()
    saved.update(request=request, args=args); calls.clear()
    from alt_deploy import setup_recovery_sssd_start as start
    return start, request, args, calls, states


def test_one_fixed_start_has_durable_intent_stable_invocation_and_no_trust_claim(tmp_path):
    start, request, args, calls, states = scenario(tmp_path)
    before = args['collect']()
    receipt = start.start_once(request, **args)
    assert receipt['status'] == 'sssd_started' and receipt['trust_verified'] is False
    assert receipt['invocation_id'] == 'a' * 32 and receipt['main_pid'] == 123
    assert args['collect']() == before
    assert [command for command in calls if command[1] == 'start'] == [
        ['/usr/bin/systemctl', 'start', 'sssd.service', '--job-mode=ignore-requirements']]
    calls.clear()
    assert start.verify_started(request, receipt, **args) == receipt
    assert not any(command[1] in ('start', 'stop', 'restart', 'reload') for command in calls)
    with pytest.raises(ValueError): start.start_once(request, **args)


@pytest.mark.parametrize('change', ['extra', 'approval', 'unit', 'opaque', 'policy_receipt', 'services_receipt', 'keytab', 'pending_job', 'active', 'environment_file', 'nonzero_restart'])
def test_changed_preconditions_refuse_start(tmp_path, change):
    start, request, args, calls, states = scenario(tmp_path)
    if change == 'extra': request['command'] = 'restart'
    elif change == 'approval': request['approval_sha256'] = 'bad'
    elif change == 'unit': states['sssd.service']['Restart'] = 'always'
    elif change == 'opaque': states['sssd.service']['Environment'] = 'UNREVIEWED=1'
    elif change == 'policy_receipt': request['policy_receipt']['snippet_sha256'] = '0' * 64
    elif change == 'services_receipt': request['service_receipt']['request_sha256'] = '0' * 64
    elif change == 'keytab': (tmp_path / 'etc/krb5.keytab').write_bytes(b'changed')
    elif change == 'active': states['sssd.service'].update(ActiveState='active', SubState='running', MainPID='123')
    elif change == 'environment_file':
        path=tmp_path/'etc/sysconfig/sssd';path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'UNREVIEWED=1')
    elif change == 'nonzero_restart':
        states['sssd.service']['NRestarts']='1';request['sssd_unit']['properties']['NRestarts']='1'
    else:
        original = args['runner']
        def pending(command, **options):
            if command[:2] == ['/usr/bin/systemctl', 'list-jobs']: return 0, '1 other.service start running\n', ''
            return original(command, **options)
        args['runner'] = pending
    with pytest.raises(ValueError): start.start_once(request, **args)
    assert not any(command[1] == 'start' for command in calls)


@pytest.mark.parametrize('failure', ['command', 'timeout', 'keytab', 'restart', 'invocation', 'other_service', 'receipt_sync'])
def test_entered_or_ambiguous_failure_is_terminal_without_retry_or_cleanup(tmp_path, monkeypatch, failure):
    start, request, args, calls, states = scenario(tmp_path)
    original = args['runner']; observed = []; backup = args['backup']; sync = backup._sync
    def broken(command, **options):
        result = original(command, **options)
        if command[1] == 'start':
            observed.append(True)
            if failure == 'command': return 1, 'SYNTHETIC_PRIVATE_OUTPUT', 'SYNTHETIC_PRIVATE_OUTPUT'
            if failure == 'timeout': raise TimeoutError('SYNTHETIC_PRIVATE_OUTPUT')
            if failure == 'keytab': (tmp_path / 'etc/krb5.keytab').write_bytes(b'changed')
            if failure == 'restart': states['sssd.service']['NRestarts'] = '1'
            if failure == 'other_service': states['smb.service'].update(ActiveState='active', SubState='running', MainPID='200')
        elif observed and failure == 'invocation' and command[-2:] == ['--', 'sssd.service']:
            states['sssd.service']['InvocationID'] = format(int(states['sssd.service']['InvocationID'], 16) + 1, '032x')
        return result
    def broken_sync(path):
        if failure == 'receipt_sync' and (path / 'started.json').exists(): raise OSError('SYNTHETIC_PRIVATE_OUTPUT')
        sync(path)
    args['runner'] = broken
    with monkeypatch.context() as local:
        local.setattr(backup, '_sync', broken_sync)
        with pytest.raises(ValueError) as error: start.start_once(request, **args)
    assert 'SYNTHETIC_PRIVATE_OUTPUT' not in str(error.value)
    leaf = start.path_for(request, backup=backup, root=tmp_path)
    assert (leaf / 'failed.json').is_file()
    assert all('SYNTHETIC_PRIVATE_OUTPUT' not in path.read_text() for path in leaf.iterdir())
    with pytest.raises(ValueError): start.start_once(request, **args)
    assert len([command for command in calls if command[1] == 'start']) == 1
    assert not any(command[1] in ('stop', 'restart', 'reload', 'reset-failed') for command in calls)


def test_readonly_verification_refuses_changed_invocation_receipt_and_failed_marker(tmp_path):
    start, request, args, calls, states = scenario(tmp_path)
    receipt = start.start_once(request, **args)
    changed = copy.deepcopy(receipt); changed['main_pid'] += 1
    with pytest.raises(ValueError): start.verify_started(request, changed, **args)
    states['sssd.service']['InvocationID'] = 'b' * 32
    with pytest.raises(ValueError): start.verify_started(request, receipt, **args)
    states['sssd.service']['InvocationID'] = receipt['invocation_id']
    (start.path_for(request, backup=args['backup'], root=tmp_path) / 'failed.json').write_text('{}')
    with pytest.raises(ValueError): start.verify_started(request, receipt, **args)


@pytest.mark.parametrize('phase', ['before', 'after'])
@pytest.mark.parametrize('change', ['keytab', 'policy_receipt', 'policy_tool', 'unit', 'environment_file'])
def test_final_native_observation_cannot_hide_file_or_history_drift(tmp_path, phase, change):
    start, request, args, calls, states = scenario(tmp_path)
    backup=args['backup'];policy=args['policy'];original=args['runner'];counts=[];started=[]
    target={'keytab':tmp_path/'etc/krb5.keytab',
        'policy_receipt':policy.path_for(request['policy_request'],backup=backup,root=tmp_path)/'verified.json',
        'policy_tool':tmp_path/'usr/sbin/sssctl',
        'unit':tmp_path/'usr/lib/systemd/system/sssd.service',
        'environment_file':tmp_path/'etc/sysconfig/sssd'}[change]
    target.parent.mkdir(parents=True,exist_ok=True)
    def racing(command, **options):
        result=original(command, **options)
        if command[1]=='start':started.append(True)
        if command[:2]==['/usr/bin/systemctl','list-jobs']:
            counts.append(True)
            if (phase=='before' and len(counts)==4) or (phase=='after' and len(counts)==10):target.write_bytes(b'changed in final manager observation')
        return result
    args['runner']=racing
    with pytest.raises(ValueError):start.start_once(request,**args)
    if phase=='before':assert not any(command[1]=='start' for command in calls)
    else:assert len([command for command in calls if command[1]=='start'])==1


@pytest.mark.parametrize('change',['plan_id','expired','future','naive','duration'])
def test_plan_identity_and_lifetime_block_before_start(tmp_path,change):
    start,request,args,calls,_=scenario(tmp_path)
    created=datetime.fromisoformat(request['plan_created_at'])
    if change=='plan_id':request['plan_id']='recovery-'+'4'*64
    elif change=='naive':request['plan_created_at']=created.replace(tzinfo=None).isoformat()
    elif change=='duration':request['plan_expires_at']=(created+timedelta(minutes=31)).isoformat()
    else:
        created+=timedelta(hours=-1 if change=='expired' else 1)
        request['plan_created_at']=created.isoformat();request['plan_expires_at']=(created+timedelta(minutes=30)).isoformat()
    with pytest.raises(ValueError):start.start_once(request,**args)
    assert not calls


def test_plan_expiring_during_final_prestart_observation_cannot_start(tmp_path,monkeypatch):
    start,request,args,calls,_=scenario(tmp_path)
    now=[datetime.now(timezone.utc)];expires=datetime.fromisoformat(request['plan_expires_at'])
    class Clock(datetime):
        @classmethod
        def now(cls,tz=None):return now[0]
    original=args['runner'];jobs=[]
    def expiring(command,**options):
        result=original(command,**options)
        if command[:2]==['/usr/bin/systemctl','list-jobs']:
            jobs.append(True)
            if len(jobs)==4:now[0]=expires
        return result
    monkeypatch.setattr(start,'datetime',Clock);args['runner']=expiring
    with pytest.raises(ValueError):start.start_once(request,**args)
    assert not any(command[1]=='start' for command in calls)
    assert (start.path_for(request,backup=args['backup'],root=tmp_path)/'failed.json').is_file()


@pytest.mark.parametrize('key',['schema_version','n_restarts','kvno'])
def test_boolean_receipt_fields_are_rejected_before_native_verification(tmp_path,key):
    start,request,args,calls,_=scenario(tmp_path)
    receipt=start.start_once(request,**args);calls.clear()
    changed=copy.deepcopy(receipt);changed[key]=bool(changed[key])
    leaf=start.path_for(request,backup=args['backup'],root=tmp_path)
    (leaf/'started.json').write_bytes(args['backup'].encoded(changed))
    with pytest.raises(ValueError):start.verify_started(request,changed,**args)
    assert not calls


def test_historical_started_receipt_can_be_checked_after_plan_expiry(tmp_path,monkeypatch):
    start,request,args,calls,_=scenario(tmp_path);receipt=start.start_once(request,**args)
    expires=datetime.fromisoformat(request['plan_expires_at'])
    class Clock(datetime):
        @classmethod
        def now(cls,tz=None):return expires
    monkeypatch.setattr(start,'datetime',Clock);calls.clear()
    assert start.verify_started(request,receipt,**args)==receipt
    assert not any(command[1] in ('start','stop','restart','reload') for command in calls)


@pytest.mark.parametrize('record',['request.json','start-intent.json'])
def test_boolean_schema_in_last_prestart_record_is_rejected_before_start(tmp_path,record):
    start,request,args,calls,_=scenario(tmp_path);original=args['runner'];jobs=[]
    def racing(command,**options):
        result=original(command,**options)
        if command[:2]==['/usr/bin/systemctl','list-jobs']:
            jobs.append(True)
            if len(jobs)==4:
                leaf=start.path_for(request,backup=args['backup'],root=tmp_path)
                path=leaf/record;value=args['backup']._json(path,root=tmp_path,owner=args['owner'])
                value['schema_version']=True;path.write_bytes(args['backup'].encoded(value))
        return result
    args['runner']=racing
    with pytest.raises(ValueError):start.start_once(request,**args)
    assert not any(command[1]=='start' for command in calls)


@pytest.mark.parametrize('record',['request.json','verified.json','stopping-smb.service.json','stopped-smb.service.json'])
def test_retained_quiescence_artifacts_refuse_boolean_schema(tmp_path,record):
    start,request,args,calls,_=scenario(tmp_path);backup=args['backup'];services=args['services']
    leaf=services.path_for(request['service_request'],backup=backup,root=tmp_path)
    path=leaf/record;value=backup._json(path,root=tmp_path,owner=args['owner'])
    value['schema_version']=True;path.write_bytes(backup.encoded(value))
    calls.clear()
    with pytest.raises(ValueError):services.verify_artifacts(request['service_request'],backup=backup,root=tmp_path,owner=args['owner'])
    assert not calls
