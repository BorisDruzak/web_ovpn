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


def test_durable_setup_and_component_apply_parser_dispatch(monkeypatch):
    from alt_deploy import setup_cli, component_setup
    calls = []
    class Service:
        def __init__(self, settings):
            self.plans = type('Plans', (), {'load': lambda *a: {'payload': {}}})()
        def apply(self, *a, **k):
            calls.append((a, k))
            return {'schema_version': 2, 'operation': 'setup_apply', 'job_id': 'synthetic', 'state': 'queued'}
    monkeypatch.setattr(setup_cli, 'SetupService', Service)
    monkeypatch.setattr(component_setup, 'ComponentSetupService', Service)
    for command, options in [('apply', ['--detach']), ('component apply', [])]:
        args = cli.build_parser().parse_args(['setup', *command.split(), 'plan', '--confirm-sha256', 'a'*64, *options])
        assert setup_cli.handle(args, object())['state'] == 'queued'
    assert calls == [(('plan', 'a'*64), {'detach': True}), (('plan', 'a'*64), {})]


def test_recovery_startup_inventory_parser_dispatch_and_safe_text(monkeypatch):
    from alt_deploy import setup_cli
    calls=[]
    class Service:
        def __init__(self,planning):calls.append(('construct',planning))
        def plan(self,run,guid):
            calls.append((run,guid))
            return {'plan_id':'recovery-inventory-'+'b'*64,'sha256':'b'*64,'expires_at':'synthetic',
                'payload':{'execution_available':False,'unit_count':172,'possible_job_count':177,
                    'inventory':{'sha256':'c'*64},'machine':{'uuid':'uuid','hostname':'alt-a1-pc3'}}}
    monkeypatch.setattr(setup_cli,'RecoveryStartupInventoryService',Service)
    monkeypatch.setattr(setup_cli,'RecoveryPlanningService',lambda settings:'planning')
    args=cli.build_parser().parse_args(['setup','recovery','startup-inventory','--failed-run','run','--computer-guid','guid'])
    result=setup_cli.handle(args,object());output=io.StringIO();setup_cli.write_text(output,result)
    assert calls==[('construct','planning'),('run','guid')]
    assert 'Execution available: false' in output.getvalue() and '172' in output.getvalue()
    for tail in (['--command','arbitrary'],['--confirm-sha256','a'*64],['--machine','other']):
        with pytest.raises(SystemExit):cli.build_parser().parse_args(['setup','recovery','startup-inventory',
            '--failed-run','run','--computer-guid','guid',*tail])


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


def test_recovery_plan_parser_has_no_execution_or_arbitrary_override():
    args = cli.build_parser().parse_args(['setup', 'recovery', 'plan', '--failed-run', 'run', '--computer-guid', 'guid'])
    assert args.setup_action == 'recovery' and args.recovery_action == 'plan'
    assert args.failed_run == 'run' and args.computer_guid == 'guid'
    for tail in (['apply'], ['plan', '--failed-run', 'run'],
                 ['plan', '--failed-run', 'run', '--computer-guid', 'guid', '--vars-file', 'anything']):
        with pytest.raises(SystemExit): cli.build_parser().parse_args(['setup', 'recovery', *tail])


def test_recovery_plan_dispatch_and_non_executable_text(monkeypatch):
    from alt_deploy import setup_cli
    calls = []
    class FakeRecovery:
        def __init__(self, settings): pass
        def plan(self, *args):
            calls.append(args)
            return {'plan_id': 'recovery-' + 'a' * 64, 'sha256': 'a' * 64, 'expires_at': 'synthetic',
                'payload': {'failed_run_id': 'run', 'machine': {'uuid': 'uuid', 'hostname': 'alt-a1-pc3', 'ip': '192.0.2.10'},
                'computer_guid': 'guid', 'computer_sid': 'sid', 'computer_ou': 'ou',
                'operation': 'replace_selected_machine_password_once', 'execution_available': False,
                'required_gates': ['reviewed_provider'], 'warnings': ['preparation_only']}}
    monkeypatch.setattr(setup_cli, 'RecoveryPlanningService', FakeRecovery)
    args = ['setup', 'recovery', 'plan', '--failed-run', 'run', '--computer-guid', 'guid']
    output = io.StringIO()
    assert cli.main(args, settings=Settings.from_env(), stdout=output) == 0
    assert 'Execution available: false' in output.getvalue()
    assert 'reviewed_provider' in output.getvalue() and 'guid' in output.getvalue()
    assert 'setup apply' not in output.getvalue()
    output = io.StringIO()
    assert cli.main(['--json', *args], settings=Settings.from_env(), stdout=output) == 0
    assert json.loads(output.getvalue())['payload']['execution_available'] is False
    assert calls == [('run', 'guid')] * 2
