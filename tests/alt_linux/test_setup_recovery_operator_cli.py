import io,json
import pytest
from alt_deploy import cli,setup_cli
from alt_deploy.config import Settings

@pytest.mark.parametrize('action',['execution-plan','continue-plan','status'])
def test_operator_history_pair_only(action):
    argv=['setup','recovery',action,'--failed-run','run','--computer-guid','guid']
    parsed=cli.build_parser().parse_args(argv);assert parsed.recovery_action==action
    for override in (['--machine','other'],['--password','secret'],['--root','/tmp'],['--vars-file','file']):
        with pytest.raises(SystemExit):cli.build_parser().parse_args(argv+override)

def test_apply_requires_exact_operator_sha_and_no_other_arguments():
    argv=['setup','recovery','apply','operator','--confirm-sha256','sha']
    assert cli.build_parser().parse_args(argv).confirm_sha256=='sha'
    with pytest.raises(SystemExit):cli.build_parser().parse_args(argv[:4])

def test_cli_apply_dispatches_fixed_coordinator_once(monkeypatch):
    calls=[]
    class Operator:
        def __init__(self,settings):pass
        def apply(self,*args):calls.append(args);return dict(status='normal_policy_handoff_succeeded')
    monkeypatch.setattr(setup_cli,'operator_for_plan',lambda settings,plan_id,sha:Operator(settings))
    output=io.StringIO()
    assert cli.main(['--json','setup','recovery','apply','operator','--confirm-sha256','sha'],settings=Settings.from_env(),stdout=output)==0
    assert calls==[('operator','sha')] and json.loads(output.getvalue())['status']=='normal_policy_handoff_succeeded'
