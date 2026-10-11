from __future__ import annotations

import copy
import json
import os

import pytest

from test_setup_recovery_backup import fixture
from test_setup_recovery_native import META, PASSWORD, metadata_dump, keytab_dump


def scenario(root, *, version=None):
    from alt_deploy import setup_recovery_native as native
    backup, request, collect = fixture(root)
    if version is not None:
        original_collect = collect
        def collect():
            facts = original_collect(); facts['samba_version'] = version
            return facts
        request['facts'] = collect(); request['snapshot_sha256'] = backup.digest(request['facts'])
    receipt = backup.create(request, collect=collect, root=root, owner=os.geteuid())
    document = {'schema_version': 1, 'backup_request': request, 'backup_receipt': receipt,
                'metadata': dict(META), 'credential_sha256': 'd'*64, 'source_sha256': 'e'*64}
    calls = []
    def runner(command, *, environment, input_text=None, timeout=20):
        calls.append((command, input_text))
        work = command[command.index('--bind')+1]
        from pathlib import Path
        if 'requestodj' in command:
            assert (Path(work)/'private/secrets.tdb').read_bytes() == b'SYNTHETIC_SECRET_CONTENT'
        if 'composeodj' in command: return 0, 'c3ludGhldGljLWJsb2I=\n', ''
        if 'dumpinfo' in command: return 0, metadata_dump(), ''
        if 'list' in command: return 0, keytab_dump(), ''
        if '/usr/bin/python3' in command: return 0, 'true\n', ''
        return 0, '', ''
    return backup, native, document, collect, runner, calls


def api():
    from alt_deploy import setup_recovery_rehearsal
    return setup_recovery_rehearsal


def create(root, data):
    backup, native, request, collect, runner, _ = data
    return api().create(request, PASSWORD, backup=backup, native=native, collect=collect,
                        runner=runner, root=root, owner=os.geteuid())


def test_bound_rehearsal_seeds_backup_and_keeps_only_safe_receipt(tmp_path):
    data = scenario(tmp_path)
    receipt = create(tmp_path, data)
    backup, native, request, collect, runner, calls = data
    assert receipt['status'] == 'local_rehearsal_verified'
    assert receipt['request_sha256'] == backup.digest(request)
    assert receipt['credential_sha256'] == request['credential_sha256']
    assert PASSWORD not in json.dumps(receipt)
    assert len(calls) == 8
    assert all(PASSWORD not in str(command) for command, _ in calls)
    leaf = api().path_for(request, backup=backup, root=tmp_path)
    assert {p.name for p in leaf.iterdir()} == {'request.json', 'verified.json'}
    assert backup.verify(request['backup_request'], root=tmp_path, owner=os.geteuid()) == request['backup_receipt']
    assert api().verify(request, backup=backup, collect=collect, root=tmp_path, owner=os.geteuid()) == receipt
    with pytest.raises(ValueError): create(tmp_path, data)


@pytest.mark.parametrize('changed', ['schema', 'extra', 'credential', 'source', 'hostname', 'backup', 'password', 'snapshot'])
def test_invalid_rehearsal_is_refused_before_native_commands(tmp_path, changed):
    data = scenario(tmp_path); request = data[2]
    password = PASSWORD
    if changed == 'schema': request['schema_version'] = True
    elif changed == 'extra': request['command'] = 'join'
    elif changed == 'credential': request['credential_sha256'] = 'bad'
    elif changed == 'source': request['source_sha256'] = 'bad'
    elif changed == 'hostname': request['metadata']['hostname'] = 'alt-a1-pc4'
    elif changed == 'backup': request['backup_receipt']['manifest_sha256'] = 'f'*64
    elif changed == 'password': password += '\n'
    else: request['backup_request']['facts']['clock_synchronized'] = False
    with pytest.raises(ValueError):
        api().create(request, password, backup=data[0], native=data[1], collect=data[3], runner=data[4],
                     root=tmp_path, owner=os.geteuid())
    assert data[-1] == []


@pytest.mark.parametrize('step', range(8))
def test_every_native_failure_preserves_backup_and_excludes_replay(tmp_path, step):
    data = list(scenario(tmp_path)); original = data[4]; count = [0]
    def broken(command, **kwargs):
        current = count[0]; count[0] += 1
        if current == step: return 1, PASSWORD, PASSWORD
        return original(command, **kwargs)
    data[4] = broken
    with pytest.raises(ValueError, match='rehearsal failed'): create(tmp_path, data)
    leaf = api().path_for(data[2], backup=data[0], root=tmp_path)
    assert {p.name for p in leaf.iterdir()} == {'request.json', 'failed.json'}
    assert PASSWORD not in ''.join(p.read_text() for p in leaf.iterdir())
    with pytest.raises(ValueError): create(tmp_path, data)
    with pytest.raises(ValueError): api().verify(data[2], backup=data[0], collect=data[3], root=tmp_path, owner=os.geteuid())
    assert data[0].verify(data[2]['backup_request'], root=tmp_path, owner=os.geteuid()) == data[2]['backup_receipt']


def test_post_rehearsal_snapshot_drift_leaves_failed_evidence(tmp_path):
    data = list(scenario(tmp_path)); original = data[3]; count = [0]
    def changed():
        count[0] += 1
        result = copy.deepcopy(original())
        if count[0] > 1: result['clock_synchronized'] = False
        return result
    data[3] = changed
    with pytest.raises(ValueError): create(tmp_path, data)
    leaf = api().path_for(data[2], backup=data[0], root=tmp_path)
    assert (leaf/'failed.json').exists() and not (leaf/'verified.json').exists()


def test_exact_installed_alt_package_version_is_supported(tmp_path):
    assert create(tmp_path,scenario(tmp_path,version='4.21.9-alt4.p11.1'))['status']=='local_rehearsal_verified'


def test_other_unreviewed_native_version_is_refused(tmp_path):
    data=scenario(tmp_path,version='4.22.0')
    with pytest.raises(ValueError): create(tmp_path,data)
    assert data[-1]==[]


def test_visible_marker_after_sync_failure_cannot_be_verified(tmp_path,monkeypatch):
    data=scenario(tmp_path);backup=data[0]
    leaf=api().path_for(data[2],backup=backup,root=tmp_path)
    original=backup._sync
    def failed_sync(path):
        if path==leaf and (leaf/'verified.json').exists():raise OSError('synthetic fsync failure')
        original(path)
    with monkeypatch.context() as patch:
        patch.setattr(backup,'_sync',failed_sync)
        with pytest.raises(ValueError):create(tmp_path,data)
    assert (leaf/'verified.json').exists() and (leaf/'failed.json').exists()
    with pytest.raises(ValueError):api().verify(data[2],backup=backup,collect=data[3],root=tmp_path,owner=os.geteuid())
