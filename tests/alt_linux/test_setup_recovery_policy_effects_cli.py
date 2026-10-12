import io,json

import pytest

from alt_deploy import cli,setup_cli
from alt_deploy.config import Settings


def test_effect_cli_has_only_history_pair_no_execution_override():
    argv=['setup','recovery','policy-effects','--failed-run','run','--computer-guid','guid']
    assert cli.build_parser().parse_args(argv).recovery_action=='policy-effects'
    for extra in (['--root','/tmp'],['--machine','other'],['--action','start'],['--vars-file','file']):
        with pytest.raises(SystemExit):cli.build_parser().parse_args([*argv,*extra])


def test_effect_cli_prints_false_authority_and_json(monkeypatch):
    calls=[]
    class Service:
        def __init__(self,planning):pass
        def plan(self,*args):
            calls.append(args)
            return dict(plan_id='recovery-policy-effects-'+'a'*64,sha256='a'*64,expires_at='synthetic',
                payload=dict(machine=dict(uuid='uuid',hostname='alt-a1-pc3'),failed_run_id='run',execution_available=False,
                    effect_inventory_sha256='b'*64,unreviewed_key_count=2,defaults_reviewed=False,effects_reviewed=False,
                    review_requirements=['unknown_configured_keys','terminal_handoff']))
    monkeypatch.setattr(setup_cli,'RecoveryPlanningService',lambda settings:object())
    monkeypatch.setattr(setup_cli,'RecoveryPolicyEffectsService',Service)
    argv=['setup','recovery','policy-effects','--failed-run','run','--computer-guid','guid']
    output=io.StringIO();assert cli.main(argv,settings=Settings.from_env(),stdout=output)==0
    assert 'Execution available: false' in output.getvalue() and 'Effects reviewed: false' in output.getvalue()
    assert 'Defaults reviewed: false' in output.getvalue() and 'Unreviewed configured keys: 2' in output.getvalue()
    assert 'setup apply' not in output.getvalue()
    output=io.StringIO();assert cli.main(['--json',*argv],settings=Settings.from_env(),stdout=output)==0
    assert json.loads(output.getvalue())['payload']['effects_reviewed'] is False and calls==[('run','guid')]*2
