"""Only the exact operator recovery namespace can call the one-shot service."""
import io
import json
from types import SimpleNamespace

import pytest

from alt_deploy import cli
from test_setup_partial_local_state import control


def test_partial_local_cli_only_dispatches_exact_plan_apply_status(monkeypatch):
    module = control('setup_partial_local')
    calls = []
    class Service:
        def __init__(self, settings): pass
        def plan(self, job): calls.append(('plan', job)); return {'status': 'planned'}
        def apply(self, plan, sha): calls.append(('apply', plan, sha)); return {'status': 'successful'}
        def status(self, plan): calls.append(('status', plan)); return {'status': 'planned'}
    monkeypatch.setattr(module, 'PartialLocalService', Service)
    for args in (['plan','job-example'], ['apply','partial-local-'+'a'*64,'--confirm-sha256','a'*64], ['status','partial-local-'+'a'*64]):
        output = io.StringIO()
        assert cli.main(['--json','setup','recovery','partial-local',*args], settings=SimpleNamespace(), stdout=output) == 0
        assert json.loads(output.getvalue())['status'] in ('planned','successful')
    assert [call[0] for call in calls] == ['plan','apply','status']


def test_cli_rejects_paths_commands_roles_missing_confirmation_and_abbreviation():
    parser = cli.build_parser()
    for args in (['apply','partial-local-example'], ['plan','job-example','--root','/tmp/unsafe'],
                 ['plan','job-example','--command','write'], ['plan','job-example','--role','domain_join'],
                 ['apply','partial-local-example','--confirm-sha','a'*64]):
        with pytest.raises(SystemExit): parser.parse_args(['setup','recovery','partial-local',*args])
