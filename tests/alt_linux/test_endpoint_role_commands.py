from pathlib import Path
import os
import subprocess
import sys

import pytest
import yaml


ROLE = Path(__file__).resolve().parents[2] / 'deploy/alt-linux/ansible/roles/software_endpoint_agent/tasks/main.yml'


def command(name):
    tasks = yaml.safe_load(ROLE.read_text(encoding='utf-8'))
    block = next(task['block'] for task in tasks if 'block' in task)
    task = next(task for task in block if task['name'] == name)
    return task['ansible.builtin.command']['argv']


@pytest.mark.parametrize('failed_tool', [None, 'rpm2cpio', 'cpio'])
def test_fingerprint_checks_each_tool_and_executes_only_exact_payload(tmp_path, monkeypatch, failed_tool):
    argv = command('Derive hardware fingerprint from the exact RPM payload')
    staging = tmp_path / 'staging with spaces; no shell'
    staging.mkdir()
    calls = []
    executed = []

    def run(args, **kwargs):
        calls.append(args)
        assert kwargs['check'] is True
        if args[0] == failed_tool:
            raise subprocess.CalledProcessError(1, args)
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr(subprocess, 'run', run)
    monkeypatch.setattr(os, 'execv', lambda path, args: executed.append((path, args)))
    monkeypatch.setattr(sys, 'argv', ['probe', str(staging)])
    if failed_tool:
        with pytest.raises(subprocess.CalledProcessError):
            exec(compile(argv[2], '<fingerprint>', 'exec'), {})
        assert not executed
    else:
        exec(compile(argv[2], '<fingerprint>', 'exec'), {})
        assert calls[0] == ['rpm2cpio', str(staging / 'endpoint-agent.rpm')]
        assert calls[1] == ['cpio', '-idm', '--quiet', './usr/lib64/endpoint-agent/release-bundle/*']
        binary = str(staging / 'fingerprint/usr/lib64/endpoint-agent/release-bundle/pc_agent/pc_agent')
        assert executed == [(binary, [binary, '--print-hardware-fingerprint'])]


@pytest.mark.parametrize('credential,first_claim,second_claim,expected', [
    (False, False, False, 1), (True, True, False, 1),
    (True, False, True, 1), (True, False, False, 0),
])
def test_enrollment_wait_requires_credential_and_both_claims_finalized(tmp_path, monkeypatch, credential, first_claim, second_claim, expected):
    argv = command('Wait for Endpoint enrollment completion and claim finalization')
    paths = [tmp_path / name for name in ['credential', 'first claim', 'second claim']]
    for path, present in zip(paths, [credential, first_claim, second_claim]):
        if present:
            path.write_text('synthetic', encoding='utf-8')
    monkeypatch.setattr(sys, 'argv', ['probe', *map(str, paths)])
    with pytest.raises(SystemExit) as result:
        exec(compile(argv[2], '<enrollment>', 'exec'), {})
    assert result.value.code == expected
