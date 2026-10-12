import json,time
import pytest
from alt_deploy_backup.errors import BackupError
from support.backup_archive_sandbox import BackupSandbox

def diagnostic(reason='archive_command_failed',**changes):
    return dict(component='runtime',reason=reason,tar_returncode=2,zstd_returncode=0,signals=['permission_denied'],**changes)

def test_error_retains_legacy_contract_and_adds_safe_optional_diagnostic():
    legacy=BackupError('backup_component_failed','Component archive command failed',4)
    assert legacy.to_dict()==dict(status='error',error=dict(code=legacy.code,message=legacy.message))
    error=BackupError(legacy.code,legacy.message,4,diagnostic=diagnostic())
    assert error.to_dict()['error']['diagnostic']==diagnostic() and error.exit_code==4

@pytest.mark.parametrize('change',[{'component':'SYNTHETIC_SECRET'},{'reason':'SYNTHETIC_SECRET'},
    {'tar_returncode':True},{'tar_returncode':1000},{'signals':['SYNTHETIC_SECRET']},{'raw_stderr':'SYNTHETIC_SECRET'}])
def test_diagnostic_rejects_unbounded_or_secret_fields(change):
    value=diagnostic();value.update(change)
    with pytest.raises(ValueError):BackupError('backup_component_failed','fixed',4,diagnostic=value).to_dict()

@pytest.mark.parametrize('kind',['tar_failure','zstd_failure','unknown_stderr','stderr_limit','deadline'])
def test_real_archive_pipeline_failure_is_bounded_and_redacted(tmp_path,kind):
    sandbox=BackupSandbox.create(tmp_path);sandbox.seed_runtime_tree()
    path=sandbox.settings.zstd_path if kind=='zstd_failure' else sandbox.settings.tar_path
    path.write_text('#!/usr/bin/python3\nimport sys,time\n'+(
        "time.sleep(20)\n" if kind=='deadline' else
        "sys.stderr.write('SYNTHETIC_SECRET'*4096);sys.stderr.flush();time.sleep(20)\n" if kind=='stderr_limit' else
        "sys.stderr.write('SYNTHETIC_SECRET Permission denied' if "+repr(kind!='unknown_stderr')+" else 'SYNTHETIC_SECRET opaque failure');sys.exit(2)\n"))
    engine=sandbox.archive_engine();engine.capture_timeout=0.25
    started=time.monotonic()
    with pytest.raises(BackupError) as caught:engine.capture(sandbox.runtime_spec(),sandbox.tmp_bundle/'runtime.tar.zst')
    assert time.monotonic()-started<4
    output=json.dumps(caught.value.to_dict())
    assert 'SYNTHETIC_SECRET' not in output and str(tmp_path) not in output
    proof=caught.value.to_dict()['error']['diagnostic']
    expected='deadline_exceeded' if kind=='deadline' else 'stderr_limit' if kind=='stderr_limit' else 'archive_command_failed'
    assert proof['component']=='runtime' and proof['reason']==expected
    if kind=='unknown_stderr':assert proof['signals']==[]
    assert not (sandbox.tmp_bundle/'runtime.tar.zst').exists()

def test_archive_source_drift_has_specific_reason(tmp_path,monkeypatch):
    sandbox=BackupSandbox.create(tmp_path);sandbox.seed_runtime_tree();engine=sandbox.archive_engine()
    original=engine._run_capture_pipeline
    def changed(*args):
        original(*args);sandbox.settings.workstationctl_path.write_text('changed')
    monkeypatch.setattr(engine,'_run_capture_pipeline',changed)
    with pytest.raises(BackupError) as caught:engine.capture(sandbox.runtime_spec(),sandbox.tmp_bundle/'runtime.tar.zst')
    assert caught.value.to_dict()['error']['diagnostic']['reason']=='source_changed'

def test_native_cli_appends_safe_diagnostic_without_rewriting_audit(tmp_path,monkeypatch,capsys):
    from alt_deploy_backup import cli
    from alt_deploy_backup.audit import AuditLog
    sandbox=BackupSandbox.create(tmp_path)
    monkeypatch.setattr(cli,'_settings',lambda env:sandbox.settings)
    AuditLog(sandbox.settings,operation_id='old',command='guard',backup_id=None).write('command_completed',status='ok')
    before=sandbox.settings.log_file.read_bytes()
    def failed(*args):raise BackupError('backup_component_failed','fixed',4,diagnostic=diagnostic())
    monkeypatch.setattr(cli,'_dispatch',failed)
    assert cli.main(['create'],environ={},effective_uid=0)==4
    assert json.loads(capsys.readouterr().out)['error']['diagnostic']==diagnostic()
    after=sandbox.settings.log_file.read_bytes();assert after.startswith(before)
    assert json.loads(after.splitlines()[-1])['diagnostic']==diagnostic()

def test_recovery_retains_safe_failure_separately_without_altering_old_records(tmp_path):
    from test_setup_recovery_controller_backup import fixture
    from alt_deploy.setup_plans import private_read
    from alt_deploy.errors import ControlError
    producer,service,plan,claim,credentials,paths,calls=fixture(tmp_path)
    original=producer.runner
    def failed(command,**kwargs):
        if command[3]=='create':return 4,json.dumps(dict(status='error',error=dict(code='backup_component_failed',message='SYNTHETIC_SECRET',diagnostic=diagnostic()))),'SYNTHETIC_SECRET'
        return original(command,**kwargs)
    producer.runner=failed
    with pytest.raises(ControlError):producer.prepare(plan['payload'])
    record=private_read(producer.failure_diagnostic_path(plan['payload']))
    assert record['failure']['diagnostic']==diagnostic()
    assert 'SYNTHETIC_SECRET' not in json.dumps(record)
    assert private_read(producer.path(plan['payload'],'.failed.json'))==dict(schema_version=1,status='failed')
    previous=list(calls)
    with pytest.raises(ControlError):producer.prepare(plan['payload'])
    assert calls==previous

def test_native_and_recovery_validators_have_same_fixed_contract():
    from alt_deploy_backup.errors import validated_diagnostic,DIAGNOSTIC_COMPONENTS,DIAGNOSTIC_REASONS,DIAGNOSTIC_SIGNALS
    from alt_deploy.setup_recovery_controller_backup import _safe_diagnostic,_COMPONENTS,_REASONS,_SIGNALS
    assert (DIAGNOSTIC_COMPONENTS,DIAGNOSTIC_REASONS,DIAGNOSTIC_SIGNALS)==(_COMPONENTS,_REASONS,_SIGNALS)
    for component in [None,*sorted(_COMPONENTS)]:
        for reason in sorted(_REASONS):
            value=diagnostic();value.update(component=component,reason=reason,tar_returncode=None,zstd_returncode=-9,signals=sorted(_SIGNALS))
            assert validated_diagnostic(value)==_safe_diagnostic(value)

def test_recovery_transport_failure_is_unknown_and_keeps_exclusion(tmp_path):
    from test_setup_recovery_controller_backup import fixture
    from alt_deploy.setup_plans import private_read
    from alt_deploy.errors import ControlError
    producer,service,plan,*_=fixture(tmp_path)
    def failed(*a,**kw):raise ValueError('SYNTHETIC_SECRET')
    producer.runner=failed
    with pytest.raises(ControlError):producer.prepare(plan['payload'])
    record=private_read(producer.failure_diagnostic_path(plan['payload']))
    assert record['failure']['operation']=='guard' and record['failure']['native_returncode'] is None
    assert record['failure']['error_code']=='UNKNOWN' and 'SYNTHETIC_SECRET' not in json.dumps(record)

@pytest.mark.parametrize('stage',['hash','publication'])
def test_archive_io_failure_reports_its_safe_stage(tmp_path,monkeypatch,stage):
    from alt_deploy_backup import archive
    sandbox=BackupSandbox.create(tmp_path);sandbox.seed_runtime_tree();engine=sandbox.archive_engine()
    def failed(*a,**kw):raise OSError('SYNTHETIC_SECRET')
    if stage=='hash':monkeypatch.setattr(engine,'_file_digest',failed)
    else:monkeypatch.setattr(archive.os,'replace',failed)
    with pytest.raises(BackupError) as caught:engine.capture(sandbox.runtime_spec(),sandbox.tmp_bundle/'runtime.tar.zst')
    assert caught.value.to_dict()['error']['diagnostic']['reason']=='archive_'+stage+'_failed'
    assert 'SYNTHETIC_SECRET' not in json.dumps(caught.value.to_dict())

def test_audit_refuses_invalid_diagnostic_without_appending(tmp_path):
    from alt_deploy_backup.audit import AuditLog
    sandbox=BackupSandbox.create(tmp_path);audit=AuditLog(sandbox.settings,operation_id='old',command='create',backup_id=None)
    audit.write('command_started',status='started');before=sandbox.settings.log_file.read_bytes()
    value=diagnostic();value['signals']=['SYNTHETIC_SECRET']
    with pytest.raises(BackupError):audit.write('command_failed',status='error',diagnostic=value)
    assert sandbox.settings.log_file.read_bytes()==before

def test_existing_archive_destination_is_identified_without_overwrite(tmp_path):
    sandbox=BackupSandbox.create(tmp_path);sandbox.seed_runtime_tree();engine=sandbox.archive_engine()
    target=sandbox.tmp_bundle/'runtime.tar.zst';target.write_bytes(b'original')
    with pytest.raises(BackupError) as caught:engine.capture(sandbox.runtime_spec(),target)
    assert caught.value.to_dict()['error']['diagnostic']['reason']=='archive_destination_failed'
    assert target.read_bytes()==b'original'

@pytest.mark.parametrize('change',['malformed','unknown','persistence'])
def test_untrusted_or_unpersisted_failure_never_exports_secrets_or_replays(tmp_path,monkeypatch,change):
    from test_setup_recovery_controller_backup import fixture
    from alt_deploy.setup_plans import private_read
    from alt_deploy.errors import ControlError
    producer,service,plan,*_=fixture(tmp_path);original=producer.runner;calls=[]
    def failure(command,**kw):
        calls.append(command[3])
        if command[3]!='create':return original(command,**kw)
        value=diagnostic()
        if change=='malformed':value['signals']=['SYNTHETIC_SECRET']
        code='SYNTHETIC_SECRET' if change=='unknown' else 'backup_component_failed'
        return 4,json.dumps(dict(status='error',error=dict(code=code,message='SYNTHETIC_SECRET',details={'secret':'SYNTHETIC_SECRET'},diagnostic=value))),'SYNTHETIC_SECRET'
    producer.runner=failure
    if change=='persistence':
        persist=producer._persist
        def interrupted(path,document):
            persist(path,document)
            if path==producer.failure_diagnostic_path(plan['payload']):raise OSError('SYNTHETIC_SECRET')
        monkeypatch.setattr(producer,'_persist',interrupted)
    with pytest.raises(ControlError):producer.prepare(plan['payload'])
    result=private_read(producer.failure_diagnostic_path(plan['payload']))
    assert 'SYNTHETIC_SECRET' not in json.dumps(result)
    if change=='malformed':assert result['failure']['diagnostic'] is None
    if change=='unknown':
        assert result['failure']['error_code']=='UNKNOWN'
        assert result['failure']['diagnostic'] is None
    assert private_read(producer.path(plan['payload'],'.failed.json'))['status']=='failed'
    previous=list(calls)
    with pytest.raises(ControlError):producer.prepare(plan['payload'])
    assert calls==previous

def test_archive_output_fsync_failure_is_not_command_unavailable(tmp_path,monkeypatch):
    from alt_deploy_backup import archive
    sandbox=BackupSandbox.create(tmp_path);sandbox.seed_runtime_tree();engine=sandbox.archive_engine()
    fsync=archive.os.fsync
    def failed(descriptor):
        import os
        if os.readlink('/proc/self/fd/'+str(descriptor)).endswith('.tmp'):raise OSError('SYNTHETIC_SECRET')
        return fsync(descriptor)
    monkeypatch.setattr(archive.os,'fsync',failed)
    with pytest.raises(BackupError) as caught:engine.capture(sandbox.runtime_spec(),sandbox.tmp_bundle/'runtime.tar.zst')
    assert caught.value.to_dict()['error']['diagnostic']['reason']=='archive_publication_failed'

def test_deadline_kills_both_children_before_bounded_cleanup_waits(tmp_path,monkeypatch):
    from alt_deploy_backup import archive
    sandbox=BackupSandbox.create(tmp_path);sandbox.seed_runtime_tree();engine=sandbox.archive_engine();engine.capture_timeout=0.1
    sandbox.settings.tar_path.write_text('#!/usr/bin/python3\nimport time;time.sleep(20)\n')
    original=archive.subprocess.Popen;events=[];children=[]
    def spawn(*args,**kwargs):
        process=original(*args,**kwargs);children.append(process);wait=process.wait;kill=process.kill
        def bounded_wait(*a,**kw):
            assert kw.get('timeout') is not None
            assert len([v for v in events if v=='kill'])==2
            return wait(*a,**kw)
        def stop():events.append('kill');return kill()
        process.wait=bounded_wait;process.kill=stop
        return process
    monkeypatch.setattr(archive.subprocess,'Popen',spawn)
    try:
        with pytest.raises(BackupError) as caught:engine.capture(sandbox.runtime_spec(),sandbox.tmp_bundle/'runtime.tar.zst')
        assert caught.value.to_dict()['error']['diagnostic']['reason']=='deadline_exceeded'
    finally:
        for child in children:
            if child.poll() is None:child.send_signal(9)

def test_separate_diagnostic_artifact_survives_synthetic_backup_rehearsal(tmp_path):
    from support.backup_rehearsal_sandbox import BackupSandbox as RehearsalSandbox
    from alt_deploy.setup_plans import private_create
    sandbox=RehearsalSandbox.create(tmp_path);sandbox.seed_complete_controller()
    path=sandbox.settings.controller_state_root/'setup-recovery-backup-failures'/('a'*64+'.json')
    private_create(path,dict(schema_version=1,identity={'fixture':'reserved'},failure=dict(schema_version=1,operation='create',native_returncode=4,error_code='backup_component_failed',diagnostic=diagnostic())))
    original=path.read_bytes();repo=sandbox.repository();bid=repo.create().backup_id
    repo.verify(bid,write_evidence=True);sandbox.rehearsal_service().rehearse(bid)
    assert path.read_bytes()==original and sandbox.repository().assert_rehearsed_eligibility(bid).backup_id==bid
