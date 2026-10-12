import json,os
import pytest

BACKUP='backup-20261011T123456Z-12345678'
START='2026-10-11T12:30:00+00:00';FINISH='2026-10-11T12:40:00+00:00'

def rows():
    result=[]
    for i,command in enumerate(('create','verify','rehearse')):
        common=dict(command=command,operation_id='op-'+command,backup_id=None if command=='create' else BACKUP)
        result.append(dict(common,timestamp=f'2026-10-11T12:3{i}:00+00:00',event='command_started',status='started'))
        result.append(dict(common,timestamp=f'2026-10-11T12:3{i}:01+00:00',event='command_failed' if command=='rehearse' else 'command_completed',status='error' if command=='rehearse' else 'ok',**({'error_code':'backup_rehearsal_failed'} if command=='rehearse' else {'result':'backup_created' if command=='create' else 'backup_verified'})))
    return result

def write(path,entries):
    path.write_text(''.join(json.dumps(row)+'\n' for row in entries));path.chmod(0o600)

def test_archival_audit_requires_exact_six_event_closed_rehearsal_failure(tmp_path):
    from alt_deploy.setup_recovery_rehearsal_probe import audit_rehearsal_failed
    path=tmp_path/'audit.log';write(path,rows());before=path.read_bytes()
    proof=audit_rehearsal_failed(path,START,FINISH,owner=os.getuid())
    assert proof['backup_id']==BACKUP and proof['rehearsal_failed'] is True
    assert set(proof)=={'backup_id','rehearsal_failed','operation_sha256'}
    assert path.read_bytes()==before

@pytest.mark.parametrize('change',['missing','extra','wrong_error','wrong_backup','wrong_operation','wrong_order','preflight_only','unsafe','incomplete'])
def test_ambiguous_or_different_rehearsal_failure_is_not_admission(tmp_path,change):
    from alt_deploy.setup_recovery_rehearsal_probe import audit_rehearsal_failed
    path=tmp_path/'audit.log';entries=rows()
    if change=='missing':entries.pop()
    elif change=='extra':entries.extend(rows())
    elif change=='wrong_error':entries[-1]['error_code']='backup_restore_failed'
    elif change=='wrong_backup':entries[-1]['backup_id']='backup-20261011T123457Z-87654321'
    elif change=='wrong_operation':entries[-1]['operation_id']='op-other'
    elif change=='wrong_order':entries[2:4],entries[4:6]=entries[4:6],entries[2:4]
    elif change=='preflight_only':entries=entries[:2];entries[-1].update(event='command_failed',status='error',error_code='backup_preflight_failed')
    write(path,entries)
    if change=='unsafe':path.chmod(0o620)
    elif change=='incomplete':path.write_bytes(path.read_bytes().rstrip(b'\n'))
    with pytest.raises(ValueError):audit_rehearsal_failed(path,START,FINISH,owner=os.getuid())

def retained_fixture(root):
    from support.backup_rehearsal_sandbox import BackupSandbox
    sandbox=BackupSandbox.create(root)
    bid=sandbox.create_verified_backup();service=sandbox.rehearsal_service()
    selected=service._create_selected_root(bid);service._extract_all(selected,sandbox.settings.backup_root/bid)
    return sandbox,bid,selected

def test_retained_bundle_and_tree_proof_preserves_all_evidence(tmp_path,monkeypatch):
    from alt_deploy import setup_recovery_rehearsal_probe as module
    sandbox,bid,selected=retained_fixture(tmp_path)
    proof=dict(old_locale_refused=True,corrected_locale_passed=True,tool_sources_sha256='a'*64)
    monkeypatch.setattr(module,'locale_proof',lambda settings,tree:proof)
    before={str(p):p.read_bytes() for p in (sandbox.settings.backup_root/bid).iterdir() if p.is_file()}
    result=module.retained_rehearsal_proof(sandbox.repository(),bid)
    assert result['backup_id']==bid and result['locale']==proof
    assert {str(p):p.read_bytes() for p in (sandbox.settings.backup_root/bid).iterdir() if p.is_file()}==before
    assert not (sandbox.settings.backup_root/bid/'rehearsal.json').exists()

@pytest.mark.parametrize('change',['tree_bytes','tree_extra','tree_symlink','missing_verification','rehearsal_present','archive_bytes'])
def test_corrupted_retained_bundle_or_tree_is_not_a_locale_admission(tmp_path,monkeypatch,change):
    from alt_deploy import setup_recovery_rehearsal_probe as module
    sandbox,bid,selected=retained_fixture(tmp_path)
    monkeypatch.setattr(module,'locale_proof',lambda *a:dict(old_locale_refused=True,corrected_locale_passed=True,tool_sources_sha256='a'*64))
    target=next((selected/'runtime').rglob('*.py'))
    if change=='tree_bytes':target.write_bytes(target.read_bytes()+b'\n')
    elif change=='tree_extra':(selected/'unexpected.json').write_text('{}')
    elif change=='tree_symlink':target.unlink();target.symlink_to('/etc/passwd')
    elif change=='missing_verification':(sandbox.settings.backup_root/bid/'verification.json').unlink()
    elif change=='rehearsal_present':(sandbox.settings.backup_root/bid/'rehearsal.json').write_text('{}')
    else:
        path=next((sandbox.settings.backup_root/bid).glob('*.tar.zst'));path.write_bytes(b'changed')
    with pytest.raises(Exception):module.retained_rehearsal_proof(sandbox.repository(),bid)

def test_fixed_locale_probe_requires_old_utf8_refusal_and_corrected_pass(tmp_path):
    import sys
    from alt_deploy.setup_recovery_rehearsal_probe import locale_proof
    sandbox,bid,selected=retained_fixture(tmp_path)
    path=sandbox.settings.ansible_playbook_path
    path.write_text('#!'+sys.executable+'\n'+
        "import locale,sys,os\nfrom pathlib import Path\n"+
        "assert Path(os.getcwd())==Path(os.environ['ANSIBLE_CONFIG']).parent\n"+
        "locale.setlocale(locale.LC_ALL,'')\n"+
        "if locale.getencoding().lower().replace('-','')!='utf8':\n print('Ansible requires the locale encoding to be UTF-8',file=sys.stderr); sys.exit(1)\n"+
        "print('ansible-playbook [core 2.18.6]' if '--version' in sys.argv else 'syntax PASS')\n")
    result=locale_proof(sandbox.settings,selected)
    assert result['old_locale_refused'] is True and result['corrected_locale_passed'] is True

def test_bound_retained_metadata_detects_later_changes_without_rewriting_evidence(tmp_path):
    from alt_deploy.setup_recovery_rehearsal_probe import retained_metadata
    sandbox,bid,selected=retained_fixture(tmp_path)
    before={str(p):p.read_bytes() for p in (sandbox.settings.backup_root/bid).iterdir() if p.is_file()}
    first=retained_metadata(sandbox.repository(),bid)
    assert retained_metadata(sandbox.repository(),bid)==first
    target=next((selected/'runtime').rglob('*.py'));target.write_bytes(target.read_bytes()+b'\n')
    assert retained_metadata(sandbox.repository(),bid)!=first
    assert {str(p):p.read_bytes() for p in (sandbox.settings.backup_root/bid).iterdir() if p.is_file()}==before

@pytest.mark.parametrize('tool',['systemd_analyze_path','zstd_path','ansible_playbook_path'])
def test_bound_retained_proof_refuses_validation_tool_replacement(tmp_path,monkeypatch,tool):
    from alt_deploy import setup_recovery_rehearsal_probe as module
    sandbox,bid,selected=retained_fixture(tmp_path)
    monkeypatch.setattr(module,'locale_proof',lambda *a:dict(old_locale_refused=True,corrected_locale_passed=True,tool_sources_sha256='a'*64))
    proof=module.retained_rehearsal_proof(sandbox.repository(),bid)
    assert module.bound_retained_proof(sandbox.repository(),proof)['retained_evidence_unchanged']
    path=getattr(sandbox.settings,tool)
    path.write_bytes(path.read_bytes()+b'\n# replacement\n')
    with pytest.raises(ValueError,match='metadata changed'):
        module.bound_retained_proof(sandbox.repository(),proof)

def test_corrective_root_transport_is_fixed_and_readiness_gated(monkeypatch):
    from types import SimpleNamespace
    from alt_deploy.setup_recovery_rehearsal_successor_runtime import RecoveryRehearsalSuccessorRuntime
    calls=[]
    def runner(command,**kwargs):
        calls.append((command,kwargs))
        return 0,json.dumps(dict(schema_version=1,native_guard=True,no_active_recovery=True,
            capacity=dict(required_free_bytes=100,actual_free_bytes=200),backup_audit=dict(backup_id=BACKUP,rehearsal_failed=True,operation_sha256='a'*64),retained={'fixture':True})),''
    runtime=RecoveryRehearsalSuccessorRuntime(SimpleNamespace(),runner=runner,readiness=lambda:dict(ready=True,checks={'fixture':True},failed_checks=[]))
    proof=runtime.controller(approved_at=START,finished_at=FINISH)
    assert proof['readiness'] is True
    command,kwargs=calls[0]
    assert command[:6]==['/usr/bin/sudo','-n','/usr/bin/python3','-I','-B','-c']
    assert json.loads(kwargs['input_text'])['request']==dict(kind='inspect',approved_at=START,finished_at=FINISH)
