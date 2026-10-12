from __future__ import annotations

import io,json

import pytest

from alt_deploy import cli,setup_cli
from alt_deploy.config import Settings


def test_policy_baseline_cli_requires_explicit_history_pair_and_has_no_override():
    args=cli.build_parser().parse_args(['setup','recovery','policy-baseline','--failed-run','run','--computer-guid','guid'])
    assert args.recovery_action=='policy-baseline' and args.failed_run=='run' and args.computer_guid=='guid'
    for extra in (['--root','/tmp'],['--machine','other'],['--vars-file','anything'],['--action','start']):
        with pytest.raises(SystemExit):cli.build_parser().parse_args(['setup','recovery','policy-baseline','--failed-run','run','--computer-guid','guid',*extra])


def test_policy_baseline_cli_dispatches_readonly_service_and_prints_no_apply_hint(monkeypatch):
    calls=[]
    class Service:
        def __init__(self,planning):pass
        def plan(self,*args):
            calls.append(args)
            return dict(plan_id='recovery-policy-baseline-'+'a'*64,sha256='a'*64,expires_at='synthetic',
                payload=dict(machine=dict(uuid='uuid',hostname='alt-a1-pc3'),failed_run_id='run',execution_available=False,
                    projection=dict(original_sha256='b'*64,tools_sha256='c'*64,defaults_verified=False),
                    review_requirements=['runtime_default_semantics','terminal_handoff']))
    monkeypatch.setattr(setup_cli,'RecoveryPlanningService',lambda settings:object())
    monkeypatch.setattr(setup_cli,'RecoveryPolicyBaselineService',Service)
    args=['setup','recovery','policy-baseline','--failed-run','run','--computer-guid','guid']
    output=io.StringIO()
    assert cli.main(args,settings=Settings.from_env(),stdout=output)==0
    assert 'Execution available: false' in output.getvalue() and 'Defaults verified: false' in output.getvalue()
    assert 'terminal_handoff' in output.getvalue() and 'setup apply' not in output.getvalue()
    output=io.StringIO()
    assert cli.main(['--json',*args],settings=Settings.from_env(),stdout=output)==0
    assert json.loads(output.getvalue())['payload']['execution_available'] is False and calls==[('run','guid')]*2
