from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest

pytest.importorskip('fcntl', reason='POSIX controller CLI')
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'deploy/alt-linux/control'))
from alt_deploy import cli
from alt_deploy.config import Settings


def test_setup_parser_contract_and_old_configure_command():
    args = cli.build_parser().parse_args(['setup', 'plan', '--machine', 'uuid', '--user', 'user', '--computer-ou', 'ou'])
    assert args.software_profile == 'core-apps'
    assert args.remote_access_profile == 'none'
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(['setup', 'apply', 'id'])
    old = cli.build_parser().parse_args(['configure', 'preview', 'uuid', '--vars-file', 'request.json'])
    assert old.configure_command == 'preview'
    for abbreviated in ('--mach', '--use', '--computer-o'):
        with pytest.raises(SystemExit):
            cli.build_parser().parse_args(['setup', 'plan', abbreviated, 'value'])


def test_cli_dispatches_actual_plan_arguments_and_text_output(monkeypatch):
    from alt_deploy import setup_cli
    calls = []
    class FakeService:
        def __init__(self, settings): pass
        def plan(self, *args):
            calls.append(args)
            return {'plan_id': 'setup-' + 'a' * 64, 'sha256': 'a' * 64,
                    'expires_at': '2026-10-11T01:00:00+00:00',
                    'payload': {'machine': {'uuid': 'uuid', 'hostname': 'alt-a1-pc3', 'ip': '192.0.2.10'},
                                'user': {'login': 'user', 'object_guid': 'guid'}, 'computer_ou': 'ou',
                                'request': {'software_profile': 'base', 'remote_access_profile': 'none'},
                                'changes': ['domain_join'], 'warnings': [], 'deferred_actions': []}}
    monkeypatch.setattr(setup_cli, 'SetupService', FakeService)
    args = ['setup', 'plan', '--machine', 'uuid', '--user', 'user', '--computer-ou', 'ou', '--software-profile', 'base']
    output = io.StringIO()
    assert cli.main(['--json', *args], settings=Settings.from_env(), stdout=output) == 0
    assert json.loads(output.getvalue())['plan_id'].startswith('setup-')
    output = io.StringIO()
    assert cli.main(args, settings=Settings.from_env(), stdout=output) == 0
    assert 'confirm-sha256' in output.getvalue() and 'domain_join' in output.getvalue()
    assert calls == [('uuid', 'user', 'ou', 'base', 'none')] * 2


def test_readonly_ad_cli_dispatch(monkeypatch):
    from alt_deploy import setup_cli
    calls = []
    class Directory:
        def user(self, login, **kwargs):
            calls.append((login, kwargs))
            return {'login': login, 'state': 'disabled', 'object_guid': 'synthetic-guid'}
    monkeypatch.setattr(setup_cli, 'directory_for_settings', lambda settings: Directory())
    output = io.StringIO()
    assert cli.main(['--json', 'ad', 'users', 'search', '--login', 'user'], settings=Settings.from_env(), stdout=output) == 0
    assert json.loads(output.getvalue())['users'][0]['state'] == 'disabled'
    assert calls == [('user', {'require_usable': False})]
