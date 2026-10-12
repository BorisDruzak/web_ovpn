from __future__ import annotations

import json
import shlex
from types import SimpleNamespace

import pytest

from alt_deploy.errors import ControlError
from alt_deploy.setup_plans import digest
from test_setup_recovery_backup import fixture
from test_setup_recovery_facts import UUID, HOST
from test_setup_recovery_state import RUN, GUID


def scenario(tmp_path, **changes):
    from alt_deploy.setup_recovery_backup_runtime import RecoveryWorkstationBackupRuntime
    _, request, collector = fixture(tmp_path)
    identity = {'claim_sha256': 'a'*64, 'machine_uuid': UUID}
    calls = []
    def runner(command, **kwargs):
        calls.append((command, kwargs))
        wire = json.loads(kwargs['input_text']); wire.pop('_worker')
        assert 'SYNTHETIC_SECRET_CONTENT' not in kwargs['input_text']
        receipt = {key: wire[key] for key in ('schema_version', 'failed_run_id', 'computer_guid',
            'claim_sha256', 'machine_uuid', 'snapshot_sha256', 'source_sha256')}
        pair = {key: wire[key] for key in ('failed_run_id', 'computer_guid')}
        receipt['backup_id'] = 'backup-' + digest(pair)
        manifest = {'schema_version': 1, 'request': wire, 'backup_id': receipt['backup_id']}
        receipt['manifest_sha256'] = digest(manifest)
        receipt.update(changes)
        return 0, json.dumps(receipt), 'SYNTHETIC_SECRET_STDERR'
    settings = SimpleNamespace(state_root=tmp_path, known_hosts_file=tmp_path/'known_hosts', private_key_file=tmp_path/'key')
    runtime = RecoveryWorkstationBackupRuntime(settings, runner=runner,
        credentials=SimpleNamespace(_reservation=lambda **pair: dict(identity)))
    runtime._fixture_collect = collector
    machine = SimpleNamespace(ip='192.0.2.10', uuid=UUID, hostname=HOST)
    return runtime, machine, request['facts'], calls, identity


@pytest.mark.parametrize('method', ['create_backup', 'verify_backup'])
def test_fixed_backup_transport_binds_claim_target_sources_and_manifest(tmp_path, method):
    runtime, machine, facts, calls, identity = scenario(tmp_path)
    receipt = getattr(runtime, method)(machine, RUN, GUID, facts)
    command, options = calls[0]
    assert command[:3] == ['/usr/bin/ssh', '-F', '/dev/null']
    assert 'StrictHostKeyChecking=yes' in command and 'BatchMode=yes' in command
    assert command[-2] == 'ansible@192.0.2.10'
    assert command[-1].startswith('sudo -n /usr/bin/python3 -I -B -c ')
    compile(shlex.split(command[-1])[-1], '<fixed-backup-wire>', 'exec')
    assert 'SYNTHETIC_SECRET' not in str(receipt)
    assert receipt['claim_sha256'] == identity['claim_sha256']
    assert ('["create"]' if method == 'create_backup' else '["verify"]') in json.loads(options['input_text'])['_worker']


@pytest.mark.parametrize('changed', ['claim_sha256', 'machine_uuid', 'snapshot_sha256', 'source_sha256', 'backup_id', 'manifest_sha256'])
def test_mismatched_backup_receipt_is_refused(tmp_path, changed):
    runtime, machine, facts, calls, _ = scenario(tmp_path, **{changed: 'changed'})
    with pytest.raises(ControlError) as caught: runtime.create_backup(machine, RUN, GUID, facts)
    assert 'SYNTHETIC_SECRET' not in str(caught.value)


def test_bad_target_and_claim_create_no_transport_call(tmp_path):
    runtime, machine, facts, calls, identity = scenario(tmp_path)
    machine.ip = '--ProxyCommand=bad'
    with pytest.raises(ControlError): runtime.create_backup(machine, RUN, GUID, facts)
    assert calls == []
    machine.ip = '192.0.2.10'; identity['machine_uuid'] = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
    with pytest.raises(ControlError): runtime.create_backup(machine, RUN, GUID, facts)
    assert calls == []


@pytest.mark.parametrize('failure', ['nonzero', 'duplicate', 'oversize', 'diagnostic', 'claim_drift'])
def test_failed_or_changed_transport_never_returns_backup_success(tmp_path, failure):
    runtime, machine, facts, calls, identity = scenario(tmp_path)
    original = runtime.runner
    def changed(*args, **kwargs):
        rc, stdout, stderr = original(*args, **kwargs)
        if failure == 'nonzero': return 1, 'SYNTHETIC_SECRET_STDOUT', stderr
        if failure == 'diagnostic': raise RuntimeError('SYNTHETIC_SECRET')
        if failure == 'duplicate': stdout = stdout[:-1] + ', "schema_version": 1}'
        if failure == 'oversize': stdout = 'x'*262145
        if failure == 'claim_drift': identity['claim_sha256'] = 'd'*64
        return rc, stdout, stderr
    runtime.runner = changed
    with pytest.raises(ControlError) as caught: runtime.create_backup(machine, RUN, GUID, facts)
    assert 'SYNTHETIC_SECRET' not in str(caught.value)


def test_generated_worker_creates_and_verifies_only_isolated_fixture(tmp_path, monkeypatch):
    import io, os, sys
    from contextlib import redirect_stdout
    runtime, machine, facts, calls, identity = scenario(tmp_path)
    fixed_collect = runtime._fixture_collect
    def execute(command, **options):
        frame=json.loads(options['input_text']); script=frame.pop('_worker')
        # Test-only fixture injection. Production wire has neither alternate
        # roots nor collector selection in its JSON request or command.
        fixture_setup = ('probe["collect"] = fixed_collect\n'
            'for name in ("create", "verify"):\n'
            '    backup[name].__kwdefaults__.update(root=fixture_root, owner=fixture_owner)\n')
        script = script.replace('try:\n    raw =', fixture_setup + 'try:\n    raw =', 1)
        from alt_deploy.setup_recovery_source_stdin import build_source_stdin
        script,encoded=build_source_stdin(script,frame)
        output = io.StringIO()
        monkeypatch.setattr(sys, 'stdin', SimpleNamespace(buffer=io.BytesIO(encoded.encode())))
        with redirect_stdout(output):
            exec(compile(script, '<isolated-wire>', 'exec'), {'fixed_collect': fixed_collect,
                'fixture_root': tmp_path, 'fixture_owner': os.geteuid()})
        return 0, output.getvalue(), ''
    runtime.runner = execute
    created = runtime.create_backup(machine, RUN, GUID, facts)
    assert runtime.verify_backup(machine, RUN, GUID, facts) == created
    assert (tmp_path/'var/lib/alt-deploy-recovery'/created['backup_id']/'verified.json').is_file()
