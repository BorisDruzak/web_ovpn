"""Fixed SSH protocol carries one bound request and does not run legacy Setup."""
import json

import pytest
from alt_deploy.setup_plans import digest

from test_setup_partial_local_state import control, prepared
from test_setup_closed_failure import partial_failure
from test_component_catalog import project
from test_component_setup import component_service


def test_runtime_uses_only_pinned_fixed_target_protocol(partial_failure, monkeypatch):
    store, payload, closed, date = prepared(partial_failure)
    plan = store.create(payload); claim = store.claim_once(plan)
    calls = []
    expected = {'schema_version':1,'claim_key':claim['claim_key'],'plan_sha256':plan['sha256'],
                'status':'unknown_requires_review','backup_sha256':None,
                'before_sha256': digest(payload['evidence']['partial_local']['native']),
                'after_sha256':None}
    def run(command, **kwargs):
        calls.append((command,kwargs)); return 0,json.dumps(expected),''
    runtime = control('setup_partial_local_runtime').PartialLocalRuntime(store.settings, runner=run)
    monkeypatch.setattr(runtime, '_code', lambda: ['# fixed synthetic probe\n', '# fixed synthetic target\n'])
    assert runtime.apply(plan, claim) == expected
    command, kwargs = calls[0]
    assert command[0] == '/usr/bin/ssh'
    assert 'StrictHostKeyChecking=yes' in command and 'ProxyCommand=none' in command
    assert command[-1].startswith('sudo -n /usr/bin/python3 -I -B -c ')
    request = json.loads(kwargs['input_text'])
    assert request['action'] == 'execute' and request['claim_key'] == claim['claim_key']
    assert request['before'] == payload['evidence']['partial_local']['native']
    assert len(calls) == 1
