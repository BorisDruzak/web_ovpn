from __future__ import annotations

import json
import os

import pytest

from test_setup_recovery_facts import scenario, UUID, HOST
from test_setup_recovery_state import RUN, GUID


def fixture(root):
    from alt_deploy import setup_recovery_backup as backup
    probe, calls, values, runner = scenario(root)
    def collect(): return probe.collect(root=root, runner=runner, owner=os.geteuid())
    facts = collect()
    request = {'schema_version': 1, 'failed_run_id': RUN, 'computer_guid': GUID,
               'claim_sha256': 'a' * 64, 'machine_uuid': UUID, 'hostname': HOST,
               'facts': facts, 'snapshot_sha256': backup.digest(facts), 'source_sha256': 'c'*64}
    return backup, request, collect


def test_protected_backup_retains_exact_bytes_and_metadata_without_secret_output(tmp_path):
    backup, request, collect = fixture(tmp_path)
    originals = {p: (tmp_path/p.lstrip('/')).read_bytes() for p in backup.AUTH_FILES}
    receipt = backup.create(request, collect=collect, root=tmp_path, owner=os.geteuid())
    assert 'SYNTHETIC_SECRET_CONTENT' not in json.dumps(receipt)
    leaf = backup.path_for(request, root=tmp_path)
    assert leaf.stat().st_mode & 0o777 == 0o700
    assert leaf.parent.stat().st_mode & 0o777 == 0o700
    manifest = json.loads((leaf/'manifest.json').read_bytes())
    assert manifest['request'] == request
    for index, path in enumerate(backup.AUTH_FILES):
        stored = leaf/'files'/str(index)
        assert stored.read_bytes() == originals[path]
        assert stored.stat().st_mode & 0o777 == request['facts']['files'][path]['mode']
        assert (tmp_path/path.lstrip('/')).read_bytes() == originals[path]
    assert backup.verify(request, root=tmp_path, owner=os.geteuid()) == receipt
    with pytest.raises(ValueError): backup.create(request, collect=collect, root=tmp_path, owner=os.geteuid())


def test_absence_is_preserved_without_creating_original_keytab(tmp_path):
    backup, request, collect = fixture(tmp_path)
    keytab = tmp_path/'etc/krb5.keytab'; keytab.unlink()
    request['facts'] = collect(); request['snapshot_sha256'] = backup.digest(request['facts'])
    backup.create(request, collect=collect, root=tmp_path, owner=os.geteuid())
    assert not keytab.exists()
    assert not (backup.path_for(request, root=tmp_path)/'files'/str(list(backup.AUTH_FILES).index('/etc/krb5.keytab'))).exists()


@pytest.mark.parametrize('guard', ['extra', 'run', 'guid', 'claim', 'uuid', 'hostname', 'hash', 'facts', 'collector'])
def test_invalid_or_stale_request_creates_no_backup(tmp_path, guard):
    backup, request, collect = fixture(tmp_path)
    if guard == 'extra': request['path'] = '/etc'
    elif guard == 'run': request['failed_run_id'] = '../../escape'
    elif guard == 'guid': request['computer_guid'] = '../escape'
    elif guard == 'claim': request['claim_sha256'] = 'z'*64
    elif guard == 'uuid': request['machine_uuid'] = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
    elif guard == 'hostname': request['hostname'] = 'alt-a1-pc4'
    elif guard == 'hash': request['snapshot_sha256'] = 'b'*64
    elif guard == 'facts': request['facts']['clock_synchronized'] = False; request['snapshot_sha256'] = backup.digest(request['facts'])
    elif guard == 'collector': collect = None
    with pytest.raises(ValueError): backup.create(request, collect=collect, root=tmp_path, owner=os.geteuid())
    assert not (tmp_path/'var/lib/alt-deploy-recovery').exists()


@pytest.mark.parametrize('unsafe', ['base_symlink', 'base_mode', 'source_symlink', 'source_mode', 'source_bytes'])
def test_redirected_or_changed_files_are_refused(tmp_path, unsafe):
    backup, request, collect = fixture(tmp_path)
    base = tmp_path/'var/lib/alt-deploy-recovery'
    source = tmp_path/'etc/krb5.keytab'
    if unsafe == 'base_symlink': base.symlink_to(tmp_path)
    elif unsafe == 'base_mode': base.mkdir(mode=0o755)
    elif unsafe == 'source_symlink': source.unlink(); source.symlink_to(tmp_path/'etc/krb5.conf')
    elif unsafe == 'source_mode': source.chmod(0o644)
    elif unsafe == 'source_bytes': source.write_bytes(b'CHANGED')
    with pytest.raises(ValueError): backup.create(request, collect=collect, root=tmp_path, owner=os.geteuid())


@pytest.mark.parametrize('corrupt', ['copy', 'manifest', 'marker', 'copy_symlink', 'copy_mode'])
def test_corrupt_backup_cannot_produce_verified_receipt(tmp_path, corrupt):
    backup, request, collect = fixture(tmp_path)
    backup.create(request, collect=collect, root=tmp_path, owner=os.geteuid())
    leaf = backup.path_for(request, root=tmp_path)
    target = leaf/'files'/'0'
    if corrupt == 'copy': target.write_bytes(b'CHANGED')
    elif corrupt == 'copy_mode': target.chmod(0o666)
    elif corrupt == 'copy_symlink': target.unlink(); target.symlink_to(tmp_path/'etc/samba/smb.conf')
    elif corrupt == 'manifest': (leaf/'manifest.json').write_text('{}')
    elif corrupt == 'marker': (leaf/'verified.json').write_text('{}')
    with pytest.raises(ValueError): backup.verify(request, root=tmp_path, owner=os.geteuid())


@pytest.mark.parametrize('failure', ['source_drift', 'fsync'])
def test_partial_failure_keeps_exclusion_without_verified_marker(tmp_path, monkeypatch, failure):
    backup, request, collect = fixture(tmp_path)
    if failure == 'source_drift':
        original = collect; calls = []
        def collect():
            calls.append(True)
            if len(calls) == 2: (tmp_path/'etc/krb5.conf').write_bytes(b'CHANGED')
            return original()
    else:
        monkeypatch.setattr(backup.os, 'fsync', lambda fd: (_ for _ in ()).throw(OSError()))
    with pytest.raises((ValueError, OSError)): backup.create(request, collect=collect, root=tmp_path, owner=os.geteuid())
    leaf = backup.path_for(request, root=tmp_path)
    assert leaf.exists() and not (leaf/'verified.json').exists()
    with pytest.raises((ValueError, OSError)): backup.create(request, collect=collect, root=tmp_path, owner=os.geteuid())


def test_visible_marker_after_failed_final_sync_is_excluded(tmp_path, monkeypatch):
    backup, request, collect = fixture(tmp_path)
    leaf = backup.path_for(request, root=tmp_path)
    original = backup._sync
    def broken(path):
        if path == leaf and (leaf/'verified.json').exists(): raise OSError()
        original(path)
    monkeypatch.setattr(backup, '_sync', broken)
    with pytest.raises(OSError): backup.create(request, collect=collect, root=tmp_path, owner=os.geteuid())
    assert (leaf/'verified.json').exists() and (leaf/'failed.json').exists()
    monkeypatch.setattr(backup, '_sync', original)
    with pytest.raises(ValueError): backup.verify(request, root=tmp_path, owner=os.geteuid())
