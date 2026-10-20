"""Only protected literal resolver policy can enter a complete workflow plan."""
from types import SimpleNamespace

import pytest

from alt_deploy.errors import ControlError
from alt_deploy.vault import VaultHealthChecker


@pytest.mark.parametrize('value',[[],None,'192.0.2.53',['resolver.example'],['192.0.2.53','192.0.2.53'],
    ['2001:db8::1','2001:0db8::1'],['127.0.0.1'],['0.0.0.0'],['224.0.0.1'],['fe80::1%eth0'],
    ['192.0.2.'+str(i) for i in range(1,6)],[True]])
def test_final_dns_rejects_ambiguous_or_nonliteral_policy(value):
    from alt_deploy.final_dns_policy import validate
    with pytest.raises(ValueError):validate(value)


def test_final_dns_canonicalizes_and_copies_only_literal_policy():
    from alt_deploy.final_dns_policy import validate
    value=['192.0.2.53','2001:0db8::53']
    assert validate(value)=={'servers':['192.0.2.53','2001:db8::53']}
    assert value==['192.0.2.53','2001:0db8::53']


@pytest.mark.parametrize('text',[
    None,'vault_unrelated: PRIVATE-SECRET-SENTINEL',
    'vault_workstation_final_dns_servers: [192.0.2.53]\nvault_workstation_final_dns_servers: [192.0.2.54]',
    'vault_workstation_final_dns_servers: [resolver.example]',
    'vault_workstation_final_dns_servers: !!python/object/apply:os.system [PRIVATE-SECRET-SENTINEL]',
])
def test_missing_or_invalid_vault_policy_blocks_only_the_complete_workflow(monkeypatch,text):
    checker=VaultHealthChecker(SimpleNamespace())
    monkeypatch.setattr(checker,'_build_checks',lambda:{'all':True})
    monkeypatch.setattr(checker,'_decrypt',lambda:text)
    assert checker.check()['status']=='ok'
    with pytest.raises(ControlError) as caught:checker.full_workflow_policy()
    assert caught.value.code=='full_workflow_policy_unavailable'
    assert 'SENTINEL' not in str(caught.value)


def test_vault_policy_returns_no_other_protected_material(monkeypatch):
    checker=VaultHealthChecker(SimpleNamespace())
    monkeypatch.setattr(checker,'_build_checks',lambda:{'all':True})
    monkeypatch.setattr(checker,'_decrypt',lambda:'vault_workstation_final_dns_servers: [192.0.2.53]\nvault_other: PRIVATE-SECRET-SENTINEL')
    assert checker.full_workflow_policy()=={'servers':['192.0.2.53']}
